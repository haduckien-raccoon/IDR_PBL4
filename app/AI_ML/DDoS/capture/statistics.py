"""Statistics accumulator for incremental calculation (similar to Java's SummaryStatistics)"""
import math
from typing import Optional


class StatisticsAccumulator:
    """
    Incremental statistics calculator using Welford's online algorithm.
    Similar to Apache Commons Math SummaryStatistics.
    
    Calculates: count, sum, mean, variance, std, min, max
    """
    
    def __init__(self):
        self.count = 0
        self.sum = 0.0
        self.min: Optional[float] = None
        self.max: Optional[float] = None
        
        # Welford's online algorithm for variance
        self.mean = 0.0
        self.m2 = 0.0  # Sum of squares of differences from mean
    
    def add_value(self, value: float) -> None:
        """Add a value to the accumulator (incremental update)"""
        if value is None:
            return
        
        self.count += 1
        self.sum += value
        
        # Update min/max
        if self.min is None or value < self.min:
            self.min = value
        if self.max is None or value > self.max:
            self.max = value
        
        # Welford's online algorithm for variance
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
    
    def get_count(self) -> int:
        """Get number of values added"""
        return self.count
    
    def get_sum(self) -> float:
        """Get sum of all values"""
        return self.sum
    
    def get_mean(self) -> float:
        """Get mean (average) of values"""
        if self.count == 0:
            return 0.0
        return self.mean
    
    def get_variance(self) -> float:
        """Get variance of values"""
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)  # Sample variance
    
    def get_std(self) -> float:
        """Get standard deviation of values"""
        if self.count < 2:
            return 0.0
        return math.sqrt(self.get_variance())
    
    def get_min(self) -> float:
        """Get minimum value"""
        if self.min is None:
            return 0.0
        return self.min
    
    def get_max(self) -> float:
        """Get maximum value"""
        if self.max is None:
            return 0.0
        return self.max
    
    def reset(self) -> None:
        """Reset all statistics"""
        self.count = 0
        self.sum = 0.0
        self.mean = 0.0
        self.m2 = 0.0
        self.min = None
        self.max = None
    
    def get_stats(self) -> dict:
        """Get all statistics as a dictionary"""
        return {
            'count': self.get_count(),
            'sum': self.get_sum(),
            'mean': self.get_mean(),
            'std': self.get_std(),
            'min': self.get_min(),
            'max': self.get_max()
        }

