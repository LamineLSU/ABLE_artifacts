rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // CALL → TEST EAX → JE (long offset)
        $pattern1 = { 85 C0 74 12 8B 45 FC }                     // TEST EAX → JE + MOV (shorter variant)
        $pattern2 = { FF 15 ?? ?? ?? ?? }                        // CALL to address (exit decision point)

    condition:
        any of them
}