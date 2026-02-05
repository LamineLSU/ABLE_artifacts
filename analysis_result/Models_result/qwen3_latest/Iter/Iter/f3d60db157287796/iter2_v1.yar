rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // Call to unknown address (evasion check)
        $pattern1 = { 85 C0 74 12 8B 45 FC }  // Test EAX + JE + MOV (evasion logic)
        $pattern2 = { E8 ?? ?? ?? ?? 8B 4D FC }  // Call with offset + MOV (exit decision)

    condition:
        any of them
}