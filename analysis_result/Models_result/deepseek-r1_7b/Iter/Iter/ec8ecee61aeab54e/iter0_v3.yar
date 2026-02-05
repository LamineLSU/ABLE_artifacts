rule Bypass_Stage0_sample
{
    meta:
        description = "Evasion bypass (Stage 0)"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? ?? }
        $pattern2 = { 8D ?? ?? ?? F6 ?? ?? 03 30 ?? ?? 5C } // More complex pattern

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}