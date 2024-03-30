package crud

import (
	"github.com/bimal2614/ginBoilerplate/database"
	"github.com/bimal2614/ginBoilerplate/src/models"
)

// CreateUser creates a new user record in the database
func CreateUser(user *models.User) error {
	if err := database.DB.Create(user).Error; err != nil {
		return err
	}
	return nil
}

// GetUser fetches a user record from the database by ID
func GetUser(id int) (*models.User, error) {
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUsers fetches all user records from the database
func GetUsers() (*[]models.User, error) {
	var users []models.User
	if err := database.DB.Find(&users).Error; err != nil {
		return nil, err
	}
	return &users, nil
}

// UpdateUser updates a user record in the database
func UpdateUser(user *models.User) error {
	if err := database.DB.Save(user).Error; err != nil {
		return err
	}
	return nil
}

// DeleteUser deletes a user record from the database by ID
func DeleteUser(id int) error {
	var user models.User
	if err := database.DB.Delete(user, id).Error; err != nil {
		return err
	}
	return nil
}

func UserExistsByEmail(email string) (*models.User, error) {
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	
	return &user, nil
}

func CheckUserName(name string) error{
	var user models.User
	return database.DB.Where("username = ?", name).First(&user).Error
}
