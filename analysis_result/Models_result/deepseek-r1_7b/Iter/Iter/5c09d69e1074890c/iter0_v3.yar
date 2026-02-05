rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting stack checks and instruction flow"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 8B 45 ?? ?? ?? ?? ?? AE EA EB AD AC AB AC EC }
        $pattern1 = { FF D2 ?? ?? 8B C0 5A 8B CE E8 ?? ?? ?? ?? AE FF D2 CA 00 41 E1 B4 AE EC CE AE EC }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? 8B 45 8B C0 5A 8B CE E8 ?? ?? AE AA 00 41 E2 3D BA AB EE AC EC }

    condition:
        any of them
}