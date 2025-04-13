import { Body, Controller, NotFoundException, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { UserDto } from './dto/user.dto';
import { RequestTokenDto } from './dto/requestToken.dto';
import { OTPType } from 'src/otp/type/otpType';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Post('register')
  async register(@Body() userDto: UserDto) {
    await this.userService.register(userDto);
    return { message: 'User created successfully and OTP sent to email' };
  }

  @Post('request-otp')
  async requestOTP(@Body() dto: RequestTokenDto) {
    const { email } = dto;
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    //send otp
    await this.userService.emailVerification(user, OTPType.OTP);
    return { message: 'OTP sent successfully.Please check email' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotDto: RequestTokenDto) {
    const { email } = forgotDto;
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.userService.emailVerification(user, OTPType.RESET_LINK);
    return {
      message: 'Password reset link has been sent.Please check your mail.',
    };
  }
}
