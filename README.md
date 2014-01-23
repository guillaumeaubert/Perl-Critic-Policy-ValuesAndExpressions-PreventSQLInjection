Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection
===========================================================

[![Build Status](https://travis-ci.org/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection.png?branch=master)](https://travis-ci.org/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection)
[![Coverage Status](https://coveralls.io/repos/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection/badge.png?branch=master)](https://coveralls.io/r/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection?branch=master)

When building SQL statements manually instead of using an ORM, any input must
be quoted or passed using placeholders to prevent the introduction of SQL
injection vectors. This policy attempts to detect the most common sources of
SQL injection in manually crafted SQL statements, by detecting the use of
variables inside interpolated strings that look like SQL statements.


INSTALLATION
------------

To install this module, run the following commands:

	perl Build.PL
	./Build
	./Build test
	./Build install


SUPPORT AND DOCUMENTATION
-------------------------

After installing, you can find documentation for this module with the
perldoc command.

	perldoc Perl::Critic::Policy::ValuesAndExpressions::PreventSQLInjection


You can also look for information at:

 * [GitHub (report bugs here)]
   (https://github.com/guillaumeaubert/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection)

 * [AnnoCPAN, Annotated CPAN documentation]
   (http://annocpan.org/dist/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection)

 * [CPAN Ratings]
   (http://cpanratings.perl.org/d/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection)

 * [MetaCPAN]
   (https://metacpan.org/release/Perl-Critic-Policy-ValuesAndExpressions-PreventSQLInjection)


LICENSE AND COPYRIGHT
---------------------

Copyright (C) 2013-2014 Guillaume Aubert

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3 as published by the Free
Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see http://www.gnu.org/licenses/
