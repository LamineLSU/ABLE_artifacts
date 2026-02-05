rule Bypass_Evasion_Exit_Paths
{
    meta:
        description = "Evasion bypass rules targeting exit paths using specific instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 1A ?? ?? ?? E8 C8 FF FF FF }
        $pattern1 = { 83 F8 ?? ?? CD ?? ?? ?? E8 C8 FF FF FF }
        $pattern2 = { 0F 85 C0 ?? ?? ?? ?? ?? ?? ?? ?? 74 0C }

    condition:
        any_of_them
}