rule FunctionPrologue {
    meta:
        description = "Identifies a standard function prologue"
        cape_options = "bp0=$prologue+0,action0=skip,bp1=$crt_call+0,action1=skip,bp2=$exit_call+0,action2=skip,count=0"
    strings:
        $prologue = { 55 8B EC FF 75 08 }
    condition:
        $prologue
}

rule CRTExitCall {
    meta:
        description = "Identifies a call to CRT exit function"
    strings:
        $crt_call = { E8 C1 FF FF FF }
    condition:
        $crt_call
}

rule ExitProcessCall {
    meta:
        description = "Identifies a call to ExitProcess"
    strings:
        $exit_call = { FF 15 68 F3 20 00 }
    condition:
        $exit_call
}