#!perl -T

use strict;
use warnings;

use Test::FailWarnings;
use Test::Perl::Critic::Policy qw( all_policies_ok );


all_policies_ok(
	-policies => [ 'PreventSQLInjection' ],
);
