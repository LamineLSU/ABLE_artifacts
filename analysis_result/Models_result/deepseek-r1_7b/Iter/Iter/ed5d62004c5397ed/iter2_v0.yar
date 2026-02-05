rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting TEST EAX near-jump instructions with specific displacements."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = {6A 5B E8 CE E8 ??: ??}
        $pattern1 = {6A 5B E9 CE E8 ??: ??}
        $pattern2 = {85 C0 74 12 E9 ??: ??}
}

Wait, no. Each pattern needs to be unique and specific.

Let me provide the correct patterns: