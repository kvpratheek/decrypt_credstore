package com.sap.multidb.controller;

import org.springframework.web.bind.annotation.RestController;

@RestController
public class EmployeeController {

//    @Autowired
//    EmployeeRepo employeeRepo;
//
//    @Autowired
//    TenantContext tenantContext;

//    @PostMapping("/employee")
//    public Employee createEmployee(@RequestParam final String tenantId, @RequestBody final Employee employee) {
//        tenantContext.setCurrentTenant(tenantId);
//        return employeeRepo.save(employee);
//    }
//
//    @GetMapping("/employee")
//    public List<Employee> getAllEmployee(@RequestParam final String tenantId) {
//        tenantContext.setCurrentTenant(tenantId);
//        return (List<Employee>) employeeRepo.findAll();
//    }
//
//    @GetMapping("/employee/{id}")
//    public Optional<Employee> getAllEmployee(@RequestParam final String tenantId, @PathVariable("id") final String employeeId) {
//        tenantContext.setCurrentTenant(tenantId);
//        return employeeRepo.findById(employeeId);
//    }
}
