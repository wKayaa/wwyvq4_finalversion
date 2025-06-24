#!/usr/bin/env python3
"""
🛡️ F8S Error Handler
Robust error handling and retry logic for F8S Framework

Author: wKayaa
Date: 2025-01-28
"""

import asyncio
import time
import traceback
from typing import Any, Callable, Optional, List, Dict
from dataclasses import dataclass
from enum import Enum
import logging


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorInfo:
    """Error information tracking"""
    timestamp: float
    function_name: str
    error_type: str
    error_message: str
    severity: ErrorSeverity
    retry_count: int
    context: Dict = None
    traceback_str: str = None


class ErrorHandler:
    """Robust error handling with retry logic and skip-on-fail"""
    
    def __init__(self, retry_count: int = 3, skip_on_fail: bool = True, 
                 verbose: bool = False, backoff_multiplier: float = 2.0):
        self.retry_count = retry_count
        self.skip_on_fail = skip_on_fail
        self.verbose = verbose
        self.backoff_multiplier = backoff_multiplier
        
        # Error tracking
        self.errors: List[ErrorInfo] = []
        self.error_counts: Dict[str, int] = {}
        self.skipped_operations: List[str] = []
        
        # Setup logging
        self.logger = logging.getLogger("F8S.ErrorHandler")
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
    
    async def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic and error handling"""
        function_name = getattr(func, '__name__', str(func))
        last_exception = None
        
        for attempt in range(self.retry_count + 1):
            try:
                # Execute the function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success - reset error count for this function
                if function_name in self.error_counts:
                    del self.error_counts[function_name]
                
                return result
                
            except Exception as e:
                last_exception = e
                severity = self._determine_error_severity(e)
                
                # Log error information
                error_info = ErrorInfo(
                    timestamp=time.time(),
                    function_name=function_name,
                    error_type=type(e).__name__,
                    error_message=str(e),
                    severity=severity,
                    retry_count=attempt,
                    context={"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
                    traceback_str=traceback.format_exc() if self.verbose else None
                )
                
                self.errors.append(error_info)
                self._increment_error_count(function_name)
                
                # Log the error
                if attempt < self.retry_count:
                    if self.verbose:
                        self.logger.warning(
                            f"Attempt {attempt + 1}/{self.retry_count + 1} failed for {function_name}: {str(e)}"
                        )
                    
                    # Calculate backoff delay
                    delay = self._calculate_backoff_delay(attempt)
                    if delay > 0:
                        await asyncio.sleep(delay)
                else:
                    # Final attempt failed
                    if severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
                        self.logger.error(
                            f"CRITICAL: {function_name} failed after {self.retry_count + 1} attempts: {str(e)}"
                        )
                    elif self.verbose:
                        self.logger.error(
                            f"Failed: {function_name} after {self.retry_count + 1} attempts: {str(e)}"
                        )
        
        # All retries exhausted
        if self.skip_on_fail:
            self.skipped_operations.append(f"{function_name}: {str(last_exception)}")
            
            if self.verbose:
                self.logger.info(f"Skipping {function_name} after exhausted retries")
            
            return None  # Return None to indicate skip
        else:
            # Re-raise the last exception
            raise last_exception
    
    def _determine_error_severity(self, exception: Exception) -> ErrorSeverity:
        """Determine error severity based on exception type"""
        error_type = type(exception).__name__
        error_message = str(exception).lower()
        
        # Critical errors (should stop execution)
        if any(keyword in error_message for keyword in [
            'authentication failed', 'invalid credentials', 'access denied',
            'permission denied', 'unauthorized', 'forbidden'
        ]):
            return ErrorSeverity.CRITICAL
        
        # High severity errors
        if any(keyword in error_message for keyword in [
            'connection refused', 'network unreachable', 'timeout',
            'ssl error', 'certificate', 'dns resolution failed'
        ]):
            return ErrorSeverity.HIGH
        
        # Medium severity errors
        if error_type in ['ConnectionError', 'TimeoutError', 'HTTPError']:
            return ErrorSeverity.MEDIUM
        
        # Low severity errors (transient issues)
        return ErrorSeverity.LOW
    
    def _calculate_backoff_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay"""
        # Base delay starts at 1 second
        base_delay = 1.0
        max_delay = 30.0  # Cap at 30 seconds
        
        delay = base_delay * (self.backoff_multiplier ** attempt)
        return min(delay, max_delay)
    
    def _increment_error_count(self, function_name: str):
        """Track error counts per function"""
        if function_name not in self.error_counts:
            self.error_counts[function_name] = 0
        self.error_counts[function_name] += 1
    
    def get_error_statistics(self) -> Dict:
        """Get comprehensive error statistics"""
        if not self.errors:
            return {"total_errors": 0, "by_severity": {}, "by_function": {}, "by_type": {}}
        
        # Count by severity
        severity_counts = {}
        for error in self.errors:
            severity = error.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by function
        function_counts = {}
        for error in self.errors:
            func = error.function_name
            function_counts[func] = function_counts.get(func, 0) + 1
        
        # Count by error type
        type_counts = {}
        for error in self.errors:
            error_type = error.error_type
            type_counts[error_type] = type_counts.get(error_type, 0) + 1
        
        # Recent errors (last 10)
        recent_errors = []
        for error in self.errors[-10:]:
            recent_errors.append({
                "timestamp": error.timestamp,
                "function": error.function_name,
                "type": error.error_type,
                "message": error.error_message[:100],
                "severity": error.severity.value
            })
        
        return {
            "total_errors": len(self.errors),
            "by_severity": severity_counts,
            "by_function": function_counts,
            "by_type": type_counts,
            "skipped_operations": len(self.skipped_operations),
            "recent_errors": recent_errors,
            "most_problematic_functions": self._get_most_problematic_functions()
        }
    
    def _get_most_problematic_functions(self, top_n: int = 5) -> List[Dict]:
        """Get functions with the most errors"""
        sorted_functions = sorted(
            self.error_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"function": func, "error_count": count}
            for func, count in sorted_functions[:top_n]
        ]
    
    def should_continue_operation(self, function_name: str, max_errors: int = 10) -> bool:
        """Check if operation should continue based on error count"""
        return self.error_counts.get(function_name, 0) < max_errors
    
    def reset_error_tracking(self):
        """Reset all error tracking (useful for new sessions)"""
        self.errors.clear()
        self.error_counts.clear()
        self.skipped_operations.clear()
        
        if self.verbose:
            self.logger.info("Error tracking reset")
    
    def log_critical_error(self, message: str, context: Dict = None):
        """Log a critical error manually"""
        error_info = ErrorInfo(
            timestamp=time.time(),
            function_name="manual",
            error_type="CriticalError",
            error_message=message,
            severity=ErrorSeverity.CRITICAL,
            retry_count=0,
            context=context or {}
        )
        
        self.errors.append(error_info)
        self.logger.critical(f"CRITICAL: {message}")
    
    def export_error_log(self, filepath: str) -> bool:
        """Export error log to file"""
        try:
            import json
            
            error_data = {
                "export_timestamp": time.time(),
                "statistics": self.get_error_statistics(),
                "detailed_errors": [
                    {
                        "timestamp": error.timestamp,
                        "function_name": error.function_name,
                        "error_type": error.error_type,
                        "error_message": error.error_message,
                        "severity": error.severity.value,
                        "retry_count": error.retry_count,
                        "context": error.context,
                        "traceback": error.traceback_str
                    }
                    for error in self.errors
                ],
                "skipped_operations": self.skipped_operations
            }
            
            with open(filepath, 'w') as f:
                json.dump(error_data, f, indent=2)
            
            self.logger.info(f"Error log exported to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export error log: {str(e)}")
            return False
    
    def print_error_summary(self):
        """Print a summary of errors encountered"""
        stats = self.get_error_statistics()
        
        print("\n📊 Error Handler Summary:")
        print(f"  Total Errors: {stats['total_errors']}")
        print(f"  Skipped Operations: {stats['skipped_operations']}")
        
        if stats['by_severity']:
            print("  By Severity:")
            for severity, count in stats['by_severity'].items():
                print(f"    {severity.upper()}: {count}")
        
        if stats['most_problematic_functions']:
            print("  Most Problematic Functions:")
            for func_info in stats['most_problematic_functions']:
                print(f"    {func_info['function']}: {func_info['error_count']} errors")
        
        if stats['recent_errors']:
            print("  Recent Errors (last few):")
            for error in stats['recent_errors'][-3:]:
                print(f"    {error['function']}: {error['message'][:50]}...")