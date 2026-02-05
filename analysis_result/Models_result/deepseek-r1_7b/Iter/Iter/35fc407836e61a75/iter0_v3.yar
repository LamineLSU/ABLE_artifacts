rule Bypass_Sample {
    meta: description = "Evasion bypass patterns for sandbox detection"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF C3 FF ?? ?? ?? ?? 74 12 } // Bypass after TEST EAX
        $pattern1 = { 6A 5B 5A 8B CE 85 C0 ?? ?? ?? ?? } // Bypass after PUSH and MOV
        $pattern2 = { A8 01 FF 75 08 FF 75 08 FF 74 07 } // Bypass after conditional jump
}

    condition: any_of_them
}