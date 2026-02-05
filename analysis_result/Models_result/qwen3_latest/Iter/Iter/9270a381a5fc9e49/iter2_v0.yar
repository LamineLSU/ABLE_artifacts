rule EvasionPatterns
{
    meta:
        description = "Detects potential evasion techniques in memory"
        cape_options = "bp0=$call_exitproc_1+0,action0=skip,bp1=$sahf_jo_into+0,action1=skip,bp2=$push_seq_call+0,action2=skip,count=0"
    strings:
        // Pattern 1: Call to ExitProcess with surrounding instructions
        $call_exitproc_1 = { 83 C4 14 52 FF D0 }
        // Pattern 2: sahf followed by jo and into instructions
        $sahf_jo_into = { 9E 70 ?? CE }
        // Pattern 3: Push sequence leading to a call
        $push_seq_call = { 51 56 50 E8 ?? ?? ?? ?? }
    condition:
        any of ($call_exitproc_1, $sahf_jo_into, $push_seq_call)
}