rule EvasionBypass {
    meta:
        description = "Malware bypass patterns targeting exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:

    condition:
        any of them
}