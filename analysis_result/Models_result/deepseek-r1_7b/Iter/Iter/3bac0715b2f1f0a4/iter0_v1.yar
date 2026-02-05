rule EvasionBypass {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 8B EC 45 00 00 00 ?? 5E 9F C0 0C CE ?? CB CA AD EA DE AB }
        $pattern1 = { 6A 23 ?? ?? ?? F7 CA CB 8A FF FF FF FF EE AC EA BA }
        $pattern2 = { 0E 4D ?? ?? 3C 5B 9F C0 14 CE ?? CA EA CD AA AE DE EA }

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}