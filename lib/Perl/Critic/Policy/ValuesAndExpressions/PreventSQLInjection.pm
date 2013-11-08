package Perl::Critic::Policy::ValuesAndExpressions::PreventSQLInjection;

use 5.006001;
use strict;
use warnings;

use base 'Perl::Critic::Policy';

use Carp;
use Data::Dumper;
use Perl::Critic::Utils;
use Readonly;
use Try::Tiny;


=head1 NAME

Perl::Critic::Policy::ValuesAndExpressions::PreventSQLInjection - Prevent SQL injection in interpolated strings.


=head1 VERSION

Version 1.0.1

=cut

our $VERSION = '1.0.1';


=head1 AFFILIATION

This is a standalone policy not part of a larger PerlCritic Policies group.


=head1 DESCRIPTION

When building SQL statements manually instead of using an ORM, any input must
be quoted or passed using placeholders to prevent the introduction of SQL
injection vectors. This policy attempts to detect the most common sources of
SQL injection in manually crafted SQL statements, by detecting the use of
variables inside interpolated strings that look like SQL statements.

In other words, this policy searches for code such as:

	my $sql = "SELECT * FROM $table WHERE field = $value";

But would leave alone:

	my $string = "Hello $world";


=head1 CONFIGURATION

There is no configuration option available for this policy.


=head1 MARKING VARIABLES AS SAFE

You can disable this policy on a particular string with the usual PerlCritic
syntax:

	my $sql = "SELECT * FROM table WHERE field = $value"; ## no critic (PreventSQLInjection)

This is however not recommended, even if you know that $value is safe because
it was previously quoted with something such as:

	my $value = $dbh->quote( $user_value );

The risk there is that someone will later modify your code and introduce unsafe
variables by accident, which will then not get reported. To prevent this, this
module has a special C<## SQL safe ($var1, $var2, ...)> syntax which allows
whitelisting specific variables:

	my $sql = "SELECT * FROM table WHERE field = $value"; ## SQL safe($value)

That said, you should always convert your code to use placeholders instead
where possible.


=head1 LIMITATIONS

There are B<many> sources of SQL injection flaws, and this module comes with no guarantee whatsoever. It focuses on the most obvious flaws, but you should still learn more about SQL injection techniques to manually detect more advanced issues.

Possible future improvements for this module:

=over 4

=item * Detect use of sprintf()

This should probably be considered a violation:

	my $sql = sprintf(
		'SELECT * FROM %s',
		$table
	);

=back

=cut

Readonly::Scalar my $DESCRIPTION => 'SQL injection risk.';
Readonly::Scalar my $EXPLANATION => 'Variables in interpolated SQL string are susceptible to SQL injection: %s';

Readonly::Scalar my $VARIABLES_REGEX => qr/
	# Ignore escaped sigils, since those wouldn't get interpreted as variables to interpolate.
	(?<!\\)
	# Allow literal, non-escapy backslashes.
	(?:\\\\)*
	(
		# The variable needs to start with a sigil.
		[\$\@]
		# Account for the dereferencing, such as "$$" or "@$".
		\$?
		# Variable name.
		(?:
			# Note: include '::' to support package variables here.
			\{(?:\w+|::)\} # Explicit {variable} name.
			|
			(?:\w|::)+	 # Variable name.
		)
		# Catch nested data structures.
		(?:
			# Allow for a dereferencing ->.
			(?:->)?
			# Can be followed by either a hash or an array.
			(?:
				\{['"]?\w+['"]?\} # Hash element.
				|
				\[['"]?\w+['"]?\] # Array element.
			)
		)*
	)
/x;


=head1 FUNCTIONS

=head2 supported_parameters()

Return an array with information about the parameters supported.

	my @supported_parameters = $policy->supported_parameters();

=cut

sub supported_parameters
{
	return ();
}


=head2 default_severity()

Return the default severify for this policy.

	my $default_severity = $policy->default_severity();

=cut

sub default_severity
{
	return $Perl::Critic::Utils::SEVERITY_HIGHEST;
}


=head2 default_themes()

Return the default themes this policy is included in.

	my $default_themes = $policy->default_themes();

=cut

sub default_themes
{
	return qw( security );
}


=head2 applies_to()

Return the class of elements this policy applies to.

	my $class = $policy->applies_to();

=cut

sub applies_to
{
	return qw(
		PPI::Token::Quote
		PPI::Token::HereDoc
	);
}


=head2 violates()

Check an element for violations against this policy.

	my $policy->violates(
		$element,
		$document,
	);

=cut

sub violates
{
	my ( $self, $element, $doc ) = @_;

	parse_comments( $self, $doc );

	# Make sure the first string looks like a SQL statement before investigating
	# further.
	return ()
		if !is_sql_statement( $element );

	my $sql_injections = [];
	my $token = $element;
	while ( defined( $token ) && $token ne '' )
	{
		# If the token is a string, we need to analyze it for interpolated
		# variables.
		if ( $token->isa( 'PPI::Token::HereDoc' ) || $token->isa( 'PPI::Token::Quote' ) ) ## no critic (ControlStructures::ProhibitCascadingIfElse)
		{
			push( @$sql_injections, @{ analyze_sql_injections( $self, $token ) // [] } );
		}
		# If it is a concatenation operator, continue to the next token.
		elsif ( $token->isa('PPI::Token::Operator') && $token->content() eq '.' )
		{
			# Skip to the next token.
		}
		# If it is a semicolon, we're at the end of the statement and we can finish
		# the process.
		elsif ( $token->isa('PPI::Token::Structure') && $token->content() eq ';' )
		{
			last;
		}
		# If it is a symbol, it is concatenated to a SQL statement which is an
		# injection risk.
		elsif ( $token->isa('PPI::Token::Symbol') )
		{
			push( @$sql_injections, $token->content() );
		}

		# Move to examining the next sibling token.
		$token = $token->snext_sibling();
	}

	# Return violations if any.
	return defined( $sql_injections ) && scalar( @$sql_injections ) != 0
		? $self->violation(
			$DESCRIPTION,
			sprintf(
				$EXPLANATION,
				join( ', ', @$sql_injections ),
			),
			$element,
		)
		: ();
}


=head2 is_sql_statement()

Return a boolean indicating whether a string is potentially the beginning of a SQL statement.

	my $is_sql_statement = is_sql_statement( $token );

=cut

sub is_sql_statement
{
	my ( $token ) = @_;
	my $content = get_token_content( $token );

	return $content =~ /\b (?: SELECT | INSERT | UPDATE | DELETE ) \b/ix
		? 1
		: 0;
}


=head2 get_token_content()

Return the text content of a PPI token.

	my $content = get_token_content( $token );

=cut

sub get_token_content
{
	my ( $token ) = @_;

	# Retrieve the string's content.
	my $content;
	if ( $token->isa('PPI::Token::HereDoc') )
	{
		my @heredoc = $token->heredoc();
		pop( @heredoc ); # Remove the heredoc termination tag.
		$content = join( '', @heredoc );
	}
	else
	{
		$content = $token->content();
	}

	return $content;
}


=head2 analyze_sql_injections()

Analyze a token and returns an arrayref of variables that are potential SQL
injection vectors.

	my $sql_injection_vector_names = analyze_sql_injections(
		$policy, # this object
		$token,
	);

=cut

sub analyze_sql_injections
{
	my ( $policy, $token ) = @_;

	my $sql_injections =
	try
	{
		# Single quoted strings aren't prone to SQL injection.
		return
			if $token->isa('PPI::Token::Quote::Single');

		# PPI treats HereDoc differently than Quote and QuoteLike for the moment,
		# this may however change in the future according to the documentation of
		# PPI.
		my $is_heredoc = $token->isa('PPI::Token::HereDoc');

		# Retrieve the string's content.
		my $content = get_token_content( $token );

		# Find the list of variables marked as safe using "## SQL safe".
		# Note: comments will appear at the end of the token, so we need to
		#       determine the ending line number instead of the beginning line
		#       number.
		my $extra_height_span =()= $content =~ /\n/g;
		my $safe_variables = get_safe_variables(
			$policy, #$self
			$token->line_number()
				# Heredoc comments will be on the same line as the opening marker.
				+ ( $is_heredoc ? 0 : $extra_height_span ),
		);

		# Find all the variables that appear in the string.
		my $unsafe_variables = [
			grep { !$safe_variables->{ $_ } }
			@{ extract_variables( $content ) }
		];

		# Based on the token type, determine if it is interpolated and report any
		# unsafe variables.
		if ( $token->isa('PPI::Token::Quote::Double') )
		{
			return $unsafe_variables
				if scalar( @$unsafe_variables ) != 0;
		}
		elsif ( $token->isa('PPI::Token::Quote::Interpolate') )
		{
			my ( $lead ) = $content =~ /\A(qq?)([^q])/s;
			croak "Unknown format for >$content<"
				if !defined( $lead );

			# Skip single quoted strings.
			return if $lead eq 'q';

			return $unsafe_variables
				if scalar( @$unsafe_variables ) != 0;
		}
		elsif ( $is_heredoc )
		{
			# Single quoted heredocs are not interpolated, so they're safe.
			# Note: '_mode' doesn't seem to be publicly accessible, and the tokenizer
			#       destroys the part of the heredoc termination marker that would
			#       allow determining whether it's interpolated, so the only option
			#       is to rely on the private property of the token here.
			return if $token->{'_mode'} ne 'interpolate';

			return $unsafe_variables
				if scalar( @$unsafe_variables ) != 0;
		}

		return;
	}
	catch
	{
		print STDERR "Error: $_\n";
		return;
	};

	return $sql_injections // [];
}


=head2 extract_variables()

Extract variable names from a string.

	my $variables = extract_variables( $string );

=cut

sub extract_variables
{
	my ( $string ) = @_;

	my $variables = [];
	while ( my ( $variable ) = $string =~ $VARIABLES_REGEX )
	{
		push( @$variables, $variable );
		$string =~ s/\Q$variable\E//g;
	}

	return $variables;
}


=head2 get_safe_variables()

Return a hashref with safe variable names as the keys.

	my $safe_variables = get_safe_variables(
		$self,
		$line_number,
	);

=cut

sub get_safe_variables
{
	my ( $self, $line_number ) = @_;

	# Validate input and state.
	croak 'Parsed comments not found'
		if !defined( $self->{'_sqlsafe'} );
	croak 'A line number is mandatory'
		if !defined( $line_number ) || ( $line_number !~ /\A\d+\Z/ );

	# If there's nothing in the cache for that line, return immediately.
	return {}
		if !exists( $self->{'_sqlsafe'}->{ $line_number } );

	# Return a hash of safe variable names.
	return {
		map
			{ $_ => 1 }
			@{ $self->{'_sqlsafe'}->{ $line_number } }
	};
}


=head2 parse_comments()

Parse the comments for the current document and identify variables marked as
SQL safe.

	parse_comments(
		$self,
		$ppi_document,
	);

=cut

sub parse_comments
{
	my ( $self, $doc ) = @_;

	# Only parse if we haven't done so already.
	return
		if defined( $self->{'_sqlsafe'} );

	# Regex to detect comments like ## SQL safe ($var1, $var2)
	my $comments_regex = qr/
		\A
		(?: [#]! .*? )?
		\s*
		# Find the ## annotation starter.
		[#][#]
		\s*
		# "SQL safe" is our keyword.
		SQL \s+ safe
		\s*
		# List of safe variables between parenthesis, space separated.
		\((.*?)\)
	/ixms;

	# Parse all the comments for this document.
	$self->{'_sqlsafe'} = {};
	my $comments = $doc->find('PPI::Token::Comment') || [];
	foreach my $comment ( @$comments )
	{
		# Determine if the line is a "SQL safe" comment.
		my ( $safe_variables ) = $comment =~ $comments_regex;
		next if !defined( $safe_variables );

		# Store list of safe variables for that line.
		push(
			@{ $self->{'_sqlsafe'}->{ $comment->line_number() } },
			split( /\s+/, $safe_variables )
		);
	}

	#print Dumper( $self->{'_sqlsafe'} ), "\n";
	return;
}


=head1 BUGS

Please report any bugs or feature requests through the web interface at
L<https://github.com/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection/issues>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

	perldoc Perl::Critic::Policy::ValuesAndExpressions::PreventSQLInjection


You can also look for information at:

=over 4

=item * GitHub (report bugs there)

L<https://github.com/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection/issues>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection>

=item * MetaCPAN

L<https://metacpan.org/release/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection>

=back


=head1 AUTHOR

L<Guillaume Aubert|https://metacpan.org/author/AUBERTG>,
C<< <aubertg at cpan.org> >>.


=head1 COPYRIGHT & LICENSE

Copyright 2013 Guillaume Aubert.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3 as published by the Free
Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see http://www.gnu.org/licenses/

=cut

1;
