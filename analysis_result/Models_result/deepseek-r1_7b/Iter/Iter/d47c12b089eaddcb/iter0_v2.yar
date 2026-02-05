rule Bypass_Sample {
    meta:
        description = "Evasion bypass of stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [8B FF ??.??.??.??] }
        $pattern1 = { [E5 ??.??.??.??] }
        $pattern2 = { [F2 ??.??.??.??] }

    patterns:
        $pattern0: mov edi, edi 8BFF (push ebp) E5 becomes ??
                   FF7508 ?? ?? ?? ?? 
                   FF15ACB04100

        $pattern1: push ebp F2 becomes ??
                   55 ?? 
                   8B EC ?? 
                   FF7508 

        $pattern2: 6A ?? 5A ?? ?? ?? ?? 
                   8B CE E8 ?? ?? ?? 
                   FF7508
}