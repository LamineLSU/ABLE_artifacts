rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E E8 ?? ?? ?? ?? }  // Test EAX + JZ + Call (evasion check)
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }     // Push 0 + ExitProcess Call (final evasion)
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 74 0E }  // Call + Test EAX + JZ (conditional check)

    condition:
        all of them
}