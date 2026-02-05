rule Bypass_Sample {
    meta:
        description = "Evasion bypass using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    $patterns:
        $pattern0 = { E8 ?? ?? ?? ?? } { six bytes long with wildcards }
        $pattern1 = { 74 0A ?? ?? ?? } { six bytes long with wildcards }
        $pattern2 = { 8DB07C0C0000 ?? 52 } { six bytes long with wildcards }

    condition:
        any of them
}