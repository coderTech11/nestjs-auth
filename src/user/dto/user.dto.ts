import { IsEmail, IsString } from 'class-validator';

export class UserDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}
