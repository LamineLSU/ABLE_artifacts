rule CustomRule {
    meta:
        description = "Detects specific instruction sequences from the provided trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-05"

    strings:
        $pattern0 = { FF D2 5E 5E 5D 5D C3 }
        $pattern1 = { E8 74 0A 00 00 55 }
        $pattern2 = { 3E D3 79 42 E8 64 59 2B 55 }

    condition:
        all of them
}