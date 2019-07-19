#!/usr/bin/perl

use strict;
use warnings;

my $username = "user1";
my $sql = "select * from users WHERE user = $username"; ## SQL safe($username)

