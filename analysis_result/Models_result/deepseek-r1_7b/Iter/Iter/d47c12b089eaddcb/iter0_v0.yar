rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection targeting specific exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 C8 FF FF FF 8B EC E8 ?? ?? ?? ?? ?? ?? ?? EA AA CA EE FB AA EA CA 00 40 E7 C3 }
        $pattern1 = { 59 8B 5A FF FF FF FF FE FF 8B 45 FF FE FF FF FF FC EA AA CA EA FF EB AA EA EC DE }
        $pattern2 = { 60 5A ?? 8B EC E8 ?? ?? ?? ?? FF EA AA EE EE AA EA EB EC AF FF }

    condition:
        any of them
}