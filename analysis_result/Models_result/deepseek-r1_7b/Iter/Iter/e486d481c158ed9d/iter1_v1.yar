rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific conditional logic before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC E8 C8 FF FF FF 55 5A FF 75 08 }
        $pattern1 = { 6A 5A 8B CE 8C 00 00 55 FF 75 08 E8 C8 FF FF FF }
        $pattern2 = { 83 C4 E8 C8 FF FF FF 55 5A FF 75 08 }
}

condition:
    (call_test_je($pattern0+0)) || (cmp_jmp($pattern1+0)) || (je_jg($pattern2+0))