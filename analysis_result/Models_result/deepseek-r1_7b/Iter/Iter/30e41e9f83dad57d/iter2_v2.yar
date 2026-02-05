rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 74 ?? ??
                     E8 ?? ?? ?? ?? 75 ?? ??
                     }
        $pattern1 = { F9 C0 85 FC 8B 45 0F 84 ?? ?? ?? ?? 
                     F9 C0 86 FC 8B 45 0F 84 ?? ?? ?? ?? 
                     }
        $pattern2 = { CE E8 ?? ?? ?? ?? 
                     FF E8 ?? ?? ?? ?? 
                     }

    condition:
        any of them
}