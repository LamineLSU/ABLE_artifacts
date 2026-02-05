rule TerminateProcess {
    meta:
        description = "Detects potential use of TerminateProcess or similar process termination calls."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-03-10"
    strings:
        $a = { 50 FF 15 ?? ?? ?? ?? FF 75 08 }  // Push EAX, Call, Push [EBP+08h]
        $b = { A8 01 75 ?? }                      // Test AL, 0x01, JNE (conditional branch)
        $c = { FF 75 08 FF 15 ?? ?? ?? ?? }       // Push [EBP+08h], Call (system call)
    condition:
        $a or $b or $c
}