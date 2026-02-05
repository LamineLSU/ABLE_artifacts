rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific anti-malware checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C1 03 C3 ?? ?? ?? ?? 8B 4D F8 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? 8B 45 FC }
        $pattern2 = { 3D 61 7A 03 C1 00 00 00 5B ?? ?? 8B E2 BE }

    condition:
        any of them
}