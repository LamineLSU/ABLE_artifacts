rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? E8 F7 25 00 00 00 } // Early call-test-je sequence
        $pattern1 = { FF 75 08 ?? FF 15 3C ?? ?? ?? ?? C0 DD } // Conditional check before exit
        $pattern2 = { 64 A1 30 ?? 8B 40 68 ?? C1 E8 08 ?? A8 01 ?? 75 10 } // Another conditional test after external function

    condition:
        any of them
}