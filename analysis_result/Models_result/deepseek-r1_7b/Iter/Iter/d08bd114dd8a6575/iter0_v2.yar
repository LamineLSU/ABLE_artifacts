rule Bypass_Evasion {
    meta:
        description = "Detect bypassed instructions leading to program exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? AE DE AC DA AC BE BA ED }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 AE DE AA CA EE CE EA ED FB }
        $pattern2 = { DD 41 E9 ?? ?? ?? ?? F3 FF ?? AE DE AE AC CE EA BA }

    condition:
        any of them
}