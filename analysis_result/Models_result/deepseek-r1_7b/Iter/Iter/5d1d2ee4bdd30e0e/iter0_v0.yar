rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass patterns targeting specific vulnerabilities"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { FF C7 43 09 5D 8B 45 5F 8E FE ?? ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}