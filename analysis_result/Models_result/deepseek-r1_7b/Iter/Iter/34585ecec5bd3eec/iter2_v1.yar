rule Bypass_Sample
{
    meta:
        description = "Evasion bypass pattern targeting 0040E7C3h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { EA 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}