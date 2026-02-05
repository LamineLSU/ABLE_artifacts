rule CRTSetup {
    meta:
        description = "CRT stack frame initialization"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 55 8B EC }  // push ebp / mov ebp, esp
    condition:
        $a
}