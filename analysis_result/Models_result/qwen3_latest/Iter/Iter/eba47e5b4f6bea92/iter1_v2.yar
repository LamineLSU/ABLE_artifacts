rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // Call to exit handler (address varies)
        $pattern1 = { E8 ?? ?? ?? ?? 50 }   // Call with offset + push (evasion check)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JE (conditional exit logic)

    condition:
        any of them
}