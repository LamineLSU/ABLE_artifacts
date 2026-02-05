rule bypass_conditional_test_0x218A {
     push 0x80
     test eax
     jz <offset>
     call 0x218A
   }