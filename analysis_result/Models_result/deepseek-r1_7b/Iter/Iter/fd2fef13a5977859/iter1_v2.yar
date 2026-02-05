rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF ?? 55 ?? 8BEC ?? A801 ?? FF7508 ?? FF153C ?? E8F7250000 ??
                      8B4068 ?? C1E808 ?? A801 ?? 7510 ?? FF7508 ?? FF1540F14200
                      8B40 ?? 50 ?? FF7508 ?? E80B000000 ?? FF7508 ?? FF15A0F14200 }
        $pattern1 = { 64A130000000 ?? FF7508 ?? FF153CF14200 ?? 50 ?? FF7508
                      ?? FF1540F14200 ?? E80B000000 ?? FF7508 ?? FF15A0F14200 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? 83C4 ?? ??
                      85 C0 0F 84 ?? ?? ?? ?? 8B4068 ?? }

    condition:
        any_of them
}