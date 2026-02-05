rule Malicious_Evasion_Check
{
    meta:
        description = "Detects a malicious evasion check involving I/O port writes, conditional jumps, and calls to ExitProcess."
        cape_options = "bp0=$out_jmp+0,action0=skip,bp1=$call_exit+0,action1=skip,bp2=$out_jmp_short+0,action2=skip,count=0"

    strings:
        $out_jmp = { E7 3C 7D 29 FF E5 }
        $call_exit = { 52 FF D0 }
        $out_jmp_short = { E7 3C 7D 29 }

    condition:
        any of ($out_jmp, $call_exit, $out_jmp_short)
}