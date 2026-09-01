package main

// How much log a device keeps, and it is deliberately not much.
//
// Four megabytes across three files bounds this at twelve, which on a laptop is somewhere
// between a few days and a few weeks of an idle agent — and comfortably covers the minutes
// before somebody noticed something was wrong, which is the only part anybody reads.
//
// Larger would be easy and is the wrong instinct: this runs on somebody's machine, not on a
// log host, and a device that quietly consumed a gigabyte describing its own health would be
// a worse citizen than one that forgot last month.
const (
	logMaxBytes  = 4 << 20
	logKeepFiles = 2
)
