rule CallPattern
{
    meta:
        description = "Detects a call sequence involving pop, push, and call instructions"
        cape_options = "bp0=$call_seq+0,action0=skip,bp1=$call_seq2+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    
    strings:
        $call_seq = { 58 FF 44 08 FF 15 ?? ?? ?? ?? } 
        $call_seq2 = { 58 FF 04 24 FF 15 ?? ?? ?? ?? }  // Alternative push encoding

    condition:
        any of them
}