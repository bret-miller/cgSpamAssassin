# cgSpamAssassin
Simple SpamAssassin interface for CommuniGate Pro using spamc/spamd

This perl script passes a message to spamc for SpamAssassin to evaluate and 
applies the resulting markup to the message using CommuniGate Pro's 
ADDHEADER response. It is currently a simple globally configured filter
that should work on both Linux and Windows systems. It is multi-threaded
on both Linux and Windows.
