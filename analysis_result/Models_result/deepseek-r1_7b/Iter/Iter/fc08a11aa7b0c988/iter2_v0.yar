rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis for specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 05 8B 45 } // Call dword ptr [00415BACh] with context
        $pattern1 = { FF 35 A0 5B 41 00 75 0C } // Another call sequence
        $pattern2 = { E8 ?? ?? ?? ?? FC ?? } // Different call or displacement pattern

    condition:
        any of them
}