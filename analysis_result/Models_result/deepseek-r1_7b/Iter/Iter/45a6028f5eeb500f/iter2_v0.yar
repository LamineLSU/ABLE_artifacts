rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass patterns targeting specific caller addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { FF C8 FF FF FF FF 8B EC ?? 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 15 AC B0 41 ?? 59 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}