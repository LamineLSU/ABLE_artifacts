rule EvasionBypass {
    meta:
        description = "Evasion bypass detection rules based on observed traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? 0F ?? CE }  // TEST EAX + JZ + MOV
        $pattern1 = { E8 ?? ?? 00 ?? ?? ?? 8B CE 45 }  // CALL ???? + TEST + POP
        $pattern2 = { ?? ?? 6A 40 5A 8B CE E8 ?? ?? }  // PUSH 0x00 + POP + PUSH
}

    condition:
        any of them
}