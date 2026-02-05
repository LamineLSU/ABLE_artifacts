rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 37 5A E8 ?? ?? ?? ?? }  // Push/Pop + Call to evasion check
        $pattern1 = { 66 83 F8 01 75 ?? }         // AX comparison + JNE to evasion logic
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? }   // Push 0 + Call to ExitProcess (final evasion)

    condition:
        all of them
}