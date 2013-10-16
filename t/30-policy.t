#!perl -T

use strict;
use warnings;

use Test::FailWarnings -allow_deps => 1;
use Test::Perl::Critic::Policy qw( all_policies_ok );


all_policies_ok(
	-policies => [ 'PreventSQLInjection' ],
);
