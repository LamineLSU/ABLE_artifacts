rule ExitProcessConditional {
    meta:
        description = "Detects conditional exit calls to ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { A1 ?? ?? ?? ?? 85 C0 74 07 }
        $pattern1 = { 53 E8 ?? ?? ?? ?? }
        $pattern2 = { 85 C0 74 ?? ?? ?? ?? }
    condition:
        any of them
}