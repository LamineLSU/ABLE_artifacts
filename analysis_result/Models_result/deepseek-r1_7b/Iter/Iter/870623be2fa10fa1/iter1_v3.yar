rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - revised to focus on exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 83 E8 25 05 00 }  // test eax, eax je 00B76190h
        $pattern1 = { 03 C3 EB 4D FC EC DD EB 00 00 01 08 E8 25 05 00 00 }  // conditional jump before exit
        $pattern2 = { 5F ED E8 E3 FA FF FF 00 B7 62 07 }  // check for conditional logic in exit decision

    condition:
        any of them
}