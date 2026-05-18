package repository


//dyanamodbav标签用于aws-sdk-go-v2的dynamodbav包进行结构体与DynamoDB项之间的映射
type User struct {
	UserID string `dynamodbav:"user_id"`
	Username string `dynamodbav:"username"`
	Password string `dynamodbav:"password"`
	Email string `dynamodbav:"email"`
}