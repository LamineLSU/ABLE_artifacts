rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting known exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B 4C 78 6F 0A 8B 5A ?? }
        $pattern1 = { 3D F9 33 CC FF 3F ?? ?? ?? }
        $pattern2 = { 03 C0 00 00 00 0C FA 4D }

    condition:
        (any of them)
}