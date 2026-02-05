rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = E8 ?? ?? ?? ?? 85 C0 74 ??  // Call + test eax + je
        $pattern1 = 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ??  // mov ecx, esi + call + test + je
        $pattern2 = 53 6A ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ??  // push + call setup for exit decision

    condition:
        any of them
}