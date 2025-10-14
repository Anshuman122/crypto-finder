
from pydantic import BaseModel, Field
from typing import List, Optional

class FunctionAnalysisRequest(BaseModel):

    name: Optional[str] = "unknown_function"
    size: int = Field(..., gt=0, description="size of function in bytes")
    instruction_count: int = Field(..., gt=0, description="Instructions' total count.")
    pcode: List[str] = Field(..., description="list of p-code operations of the function.")

class Prediction(BaseModel):

    label: str = Field(..., description="Predicted label ('crypto' or 'non-crypto').")
    confidence: float = Field(..., ge=0, le=1, description="Prediction confidence score (0 to 1).")

class AnalysisResponse(BaseModel):

    function_name: str
    prediction: Prediction
