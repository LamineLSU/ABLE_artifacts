rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 } // test/je + push/pop + call
        $pattern1 = { 33 DB 53 6A 40 53 68 40 11 0A 01 } // xor ebx, ebx + push ebx + push 0x40 + push ebx + push 0x10A1140h
        $pattern2 = { FF 15 2C A1 0A 01 } // call [0x10AA12Ch] (exit decision point)

    condition:
        any of them
}